import { defineEndpoint } from "@directus/extensions-sdk";
import Joi from "joi";
import { performance } from "perf_hooks";
import { stall } from "./utils";
import { Ikoddi } from "ikoddi-client-sdk";
import ms from "ms";
import { nanoid } from "nanoid";
import * as jwt from "jsonwebtoken";

export interface User {
  id: string;
  first_name: string | null;
  last_name: string | null;
  email: string | null;
  phone_number: string | null;
  password: string | null;
  status: "active" | "suspended" | "invited";
  role: string | null;
  provider: string;
  external_identifier: string | null;
  auth_data: string | Record<string, unknown> | null;
  app_access: boolean;
  admin_access: boolean;
}

export default defineEndpoint((router, ctx) => {
  const { env, logger, database: knex, emitter, services, getSchema } = ctx;
  const { SettingsService, ActivityService } = services;

  router.get("/verify-phonenumber", async (req, res, next) => {
    const verifyPhoneNumberSchema = Joi.object({
      phoneNumber: Joi.string().required(),
      resendOtp: Joi.boolean(),
    }).unknown();

    const STALL_TIME = env["LOGIN_STALL_TIME"] as number;
    const timeStart = performance.now();

    const { error } = verifyPhoneNumberSchema.validate(req.body);

    if (error) {
      await stall(STALL_TIME, timeStart);
      throw new InvalidPayloadError({ reason: error.message });
    }

    const phone_number = req.body.phone_number;

    const ikoddiClient = new Ikoddi()
      .withApiBaseURL(env["AUTH_SMSOTP_API_BASE_URL"] as string)
      .withApiKey(env["AUTH_SMSOTP_API_KEY"] as string)
      .withGroupId(env["AUTH_SMSOTP_GROUP_ID"] as string)
      .withOtpAppId(env["AUTH_SMSOTP_OTP_APP_ID"] as string);

    try {
      const sendOTPResponse = await ikoddiClient.sendOTP(phone_number);

      res.locals["payload"] = {
        data: sendOTPResponse,
      };
    } catch (error) {
      logger.error(error, "[IKODDI] Failed to send OTP");
      throw new InvalidProviderError();
    }

    return next();
  });

  router.get("/login", async (req, res, next) => {
    const loginWithOTPSchema = Joi.object({
      phone_number: Joi.string().required(),
      otp_code: Joi.string().required(),
      verification_key: Joi.string().required(),
    }).unknown();

    const schema = await getSchema();

    const settingsService = new SettingsService({
      knex: knex,
      schema: schema,
    });

    const activityService = new ActivityService({ knex: knex, schema: schema });

    const accountability = {
      ip: req.ip,
      role: null,
    };
    const userAgent = req.get("user-agent");
    const origin = req.get("origin");

    const STALL_TIME = env["LOGIN_STALL_TIME"] as number;
    const timeStart = performance.now();
    const provider = "ikoddi";

    const payload = {
      phone_number: req.body.phone_number,
      otp_code: req.body.otp_code,
      verification_key: req.body.verification_key,
    };

    const loginAttemptsLimiter = createRateLimiter("RATE_LIMITER", {
      duration: 0,
    }); // directus code on /api/src/rate-limiter.ts

    const { error } = loginWithOTPSchema.validate(req.body);

    if (error) {
      await stall(STALL_TIME, timeStart);
      throw new InvalidPayloadError({ reason: error.message });
    }

    const user = await knex
      .select<User & { tfa_secret: string | null }>(
        "u.id",
        "u.first_name",
        "u.last_name",
        "u.email",
        "u.phone_number",
        "u.password",
        "u.status",
        "u.role",
        "r.admin_access",
        "r.app_access",
        "u.tfa_secret",
        "u.provider",
        "u.external_identifier",
        "u.auth_data"
      )
      .from("directus_users as u")
      .leftJoin("directus_roles as r", "u.role", "r.id")
      .where("u.phone_number", phone_number)
      .first();

    const updatedPayload = await emitter.emitFilter(
      "auth.login",
      req.body,
      {
        status: "pending",
        user: user?.id,
        provider: provider,
      },
      {
        database: knex,
        schema: schema,
        accountability: accountability,
      }
    );

    const emitStatus = (status: "fail" | "success") => {
      emitter.emitAction(
        "auth.login",
        {
          payload: updatedPayload,
          status,
          user: user?.id,
          provider: provider,
        },
        {
          database: knex,
          schema: schema,
          accountability: accountability,
        }
      );
    };

    if (user?.status !== "active") {
      emitStatus("fail");

      if (user?.status === "suspended") {
        await stall(STALL_TIME, timeStart);
        throw new UserSuspendedError();
      } else {
        await stall(STALL_TIME, timeStart);
        throw new InvalidCredentialsError();
      }
    }

    const { auth_login_attempts: allowedAttempts } =
      await settingsService.readSingleton({
        fields: ["auth_login_attempts"],
      });

    if (allowedAttempts !== null) {
      loginAttemptsLimiter.points = allowedAttempts;

      try {
        await loginAttemptsLimiter.consume(user.id);
      } catch (error) {
        if (error instanceof RateLimiterRes && error.remainingPoints === 0) {
          await this.knex("directus_users")
            .update({ status: "suspended" })
            .where({ id: user.id });
          user.status = "suspended";

          // This means that new attempts after the user has been re-activated will be accepted
          await loginAttemptsLimiter.set(user.id, 0, 0);
        } else {
          throw new ServiceUnavailableError({
            service: "authentication",
            reason: "Rate limiter unreachable",
          });
        }
      }
    }

    const ikoddiClient = new Ikoddi()
      .withApiBaseURL(env["AUTH_SMSOTP_API_BASE_URL"] as string)
      .withApiKey(env["AUTH_SMSOTP_API_KEY"] as string)
      .withGroupId(env["AUTH_SMSOTP_GROUP_ID"] as string)
      .withOtpAppId(env["AUTH_SMSOTP_OTP_APP_ID"] as string);

    try {
      await ikoddiClient.verifyOTP({
        identity: payload["phone_number"],
        otp: payload["otp_code"],
        verification_key: payload["verification_key"],
      });
    } catch (error) {
      logger.error(error);
      throw new InvalidCredentialsError();
    }

    const tokenPayload = {
      id: user.id,
      role: user.role,
      app_access: user.app_access,
      admin_access: user.admin_access,
    };

    const customClaims = await emitter.emitFilter(
      "auth.jwt",
      tokenPayload,
      {
        status: "pending",
        user: user?.id,
        provider: provider,
        type: "login",
      },
      {
        database: knex,
        schema: schema,
        accountability: accountability,
      }
    );

    const accessToken = jwt.sign(customClaims, env["SECRET"] as string, {
      expiresIn: env["ACCESS_TOKEN_TTL"] as number,
      issuer: "directus",
    });

    const refreshTokenExpiration = new Date(
      /// getMilliseconds function is on directus code at  /api/src/utils/get-milliseconds.ts
      Date.now() + getMilliseconds(process.env["REFRESH_TOKEN_TTL"], 0)
    );
    // const refreshToken = nanoid(64);
    const refreshToken = nanoid(64);

    await knex("directus_sessions").insert({
      token: refreshToken,
      user: user.id,
      expires: refreshTokenExpiration,
      ip: accountability?.ip,
      user_agent: userAgent,
      origin: origin,
    });

    await knex("directus_sessions").delete().where("expires", "<", new Date());

    if (req.accountability) {
      await activityService.createOne({
        action: "login",
        user: user.id,
        ip: accountability.ip,
        user_agent: userAgent,
        origin: origin,
        collection: "directus_users",
        item: user.id,
      });
    }

    await knex("directus_users")
      .update({ last_access: new Date() })
      .where({ id: user.id });

    emitStatus("success");

    if (allowedAttempts !== null) {
      await loginAttemptsLimiter.set(user.id, 0, 0);
    }

    await stall(STALL_TIME, timeStart);

    return {
      accessToken,
      refreshToken,
      expires: getMilliseconds(env["ACCESS_TOKEN_TTL"]),
      id: user.id,
    };
  });
});

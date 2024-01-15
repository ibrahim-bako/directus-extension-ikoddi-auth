import { defineEndpoint } from "@directus/extensions-sdk";
import Joi from "joi";
import { performance } from "perf_hooks";
import { stall } from "./utils";
import { Ikoddi } from "ikoddi-client-sdk";

export default defineEndpoint(
  (router, { env, logger, database: knex, emitter, services, getSchema }) => {
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
  }
);

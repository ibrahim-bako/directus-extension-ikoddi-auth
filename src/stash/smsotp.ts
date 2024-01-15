// import { RecordNotUniqueError } from './../../errors/record-not-unique.js';
import { Router } from 'express';
import Joi from 'joi';
import { AuthDriver } from '../auth.js';
import type { AuthDriverOptions, User } from '../../types/index.js';
// import { InvalidCredentialsError, InvalidPayloadError, InvalidProviderError } from '../../errors/index.js';
import { AuthenticationService, UsersService } from '../../services/index.js';
import asyncHandler from '../../utils/async-handler.js';
import { respond } from '../../middleware/respond.js';
import { COOKIE_OPTIONS } from '../../constants.js';
import { getIPFromReq } from '../../utils/get-ip-from-req.js';
import { performance } from 'perf_hooks';
import { stall } from '../../utils/stall.js';
import { Ikoddi } from 'ikoddi-client-sdk';
import type { Accountability } from '@directus/types';
import { useEnv } from '@directus/env';
import { useLogger } from '../../logger.js';
import {
	InvalidCredentialsError,
	InvalidPayloadError,
	InvalidProviderError,
	RecordNotUniqueError,
} from '@directus/errors';

export class SMSOTPAuthDriver extends AuthDriver {
	usersService: UsersService;
	config: Record<string, any>;

	constructor(options: AuthDriverOptions, config: Record<string, any>) {
		super(options, config);
		this.usersService = new UsersService({ knex: this.knex, schema: this.schema });
		this.config = config;
	}

	async getUserID(payload: Record<string, any>): Promise<string> {
		const env = useEnv();
		const logger = useLogger();

		if (!payload['phone_number']) {
			throw new InvalidCredentialsError();
		}

		const user = await this.knex
			.select('id')
			.from('directus_users')
			.whereRaw('LOWER(??) = ?', ['phone_number', payload['phone_number'].toLowerCase()])
			.first();

		if (!user) {
			try {
				const mobileUserDefautlRoleID = await this.knex
					.select('id')
					.from('directus_roles')
					.whereRaw('name = ?', [env['DEFAULT_MOBILE_USER_ROLE']])
					.first();

				const userId = await this.usersService.createOne({
					provider: this.config['provider'],
					phone_number: payload['phone_number'],
					role: mobileUserDefautlRoleID['id'],
				});

				return userId.toString();
			} catch (e) {
				if (e instanceof RecordNotUniqueError) {
					logger.warn(e, '[SMSOTP] Failed to register user. User not unique');
					throw new InvalidProviderError();
				}

				throw e;
			}
		} else {
			return user.id;
		}
	}

	async verify(user: User, otp: string): Promise<void> {
		// eslint-disable-next-line no-console
		console.log(user, otp);
	}

	override async login(user: User, payload: Record<string, any>): Promise<void> {
		const env = useEnv();
		const logger = useLogger();

		// eslint-disable-next-line no-console
		console.log(user, payload);

		const ikoddiClient = new Ikoddi()
			.withApiBaseURL(env['AUTH_SMSOTP_API_BASE_URL'] as string)
			.withApiKey(env['AUTH_SMSOTP_API_KEY'] as string)
			.withGroupId(env['AUTH_SMSOTP_GROUP_ID'] as string)
			.withOtpAppId(env['AUTH_SMSOTP_OTP_APP_ID'] as string);

		try {
			await ikoddiClient.verifyOTP({
				identity: payload['phone_number'],
				otp: payload['otpCode'],
				verificationKey: payload['verificationKey'],
			});
		} catch (error) {
			logger.error(error);
			throw new InvalidCredentialsError();
		}
	}
}

export function createSMSOTPAuthRouter(provider: string): Router {
	const env = useEnv();
	const logger = useLogger();

	const router = Router();

	const verifyPhoneNumberSchema = Joi.object({
		phone_number: Joi.string().required(),
		resendOtp: Joi.boolean(),
	}).unknown();

	router.post(
		'/verify-phonenumber',
		asyncHandler(async (req, res, next) => {
			const STALL_TIME = env['LOGIN_STALL_TIME'] as number;
			const timeStart = performance.now();

			const { error } = verifyPhoneNumberSchema.validate(req.body);

			if (error) {
				await stall(STALL_TIME, timeStart);
				throw new InvalidPayloadError({ reason: error.message });
			}

			const phone_number = req.body.phone_number;

			const ikoddiClient = new Ikoddi()
				.withApiBaseURL(env['AUTH_SMSOTP_API_BASE_URL'] as string)
				.withApiKey(env['AUTH_SMSOTP_API_KEY'] as string)
				.withGroupId(env['AUTH_SMSOTP_GROUP_ID'] as string)
				.withOtpAppId(env['AUTH_SMSOTP_OTP_APP_ID'] as string);

			try {
				logger.warn(process.env['AUTH_SMSOTP_API_BASE_URL']);
				logger.warn(env['AUTH_SMSOTP_API_KEY']);
				logger.warn(env['SECRET']);
				logger.warn(env['AUTH_SMSOTP_GROUP_ID']);
				logger.warn(env['AUTH_SMSOTP_OTP_APP_ID']);
				const sendOTPResponse = await ikoddiClient.sendOTP(phone_number);

				res.locals['payload'] = {
					data: sendOTPResponse,
				};
			} catch (error) {
				logger.error(error, '[IKODDI] Failed to send OTP');
				throw new InvalidProviderError();
			}

			return next();
		}),
		respond,
	);

	const loginWithOTPSchema = Joi.object({
		phone_number: Joi.string().required(),
		otpCode: Joi.string().required(),
		verificationKey: Joi.string().required(),
	}).unknown();

	router.post(
		'/',
		asyncHandler(async (req, res, next) => {
			const STALL_TIME = env['LOGIN_STALL_TIME'] as number;
			const timeStart = performance.now();

			const accountability: Accountability = {
				ip: getIPFromReq(req),
				role: null,
			};

			const userAgent = req.get('user-agent');
			if (userAgent) accountability.userAgent = userAgent;

			const origin = req.get('origin');
			if (origin) accountability.origin = origin;

			const authenticationService = new AuthenticationService({
				accountability: accountability,
				schema: req.schema,
			});

			const { error } = loginWithOTPSchema.validate(req.body);

			if (error) {
				await stall(STALL_TIME, timeStart);
				throw new InvalidPayloadError({ reason: error.message });
			}

			const mode = req.body.mode || 'json';

			const { accessToken, refreshToken, expires } = await authenticationService.login(
				provider,
				req.body,
				req.body?.otp,
			);

			const payload = {
				data: { access_token: accessToken, expires },
			} as Record<string, Record<string, any>>;

			if (mode === 'json') {
				payload['data']!['refresh_token'] = refreshToken;
			}

			if (mode === 'cookie') {
				res.cookie(env['REFRESH_TOKEN_COOKIE_NAME'] as string, refreshToken, COOKIE_OPTIONS);
			}

			res.locals['payload'] = payload;

			return next();
		}),
		respond,
	);

	return router;
}

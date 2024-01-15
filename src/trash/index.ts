/// <reference types="@directus/extensions/api.d.ts" />
import { defineEndpoint } from '@directus/extensions-sdk';
import * as jwt from 'jsonwebtoken';
// import { nanoid } from 'nanoid';
// import { Request } from 'express';
import ms from 'ms';
import { nanoid } from 'nanoid';

export interface User {
	id: string;
	first_name: string | null;
	last_name: string | null;
	email: string | null;
	phone_number: string | null;
	password: string | null;
	status: 'active' | 'suspended' | 'invited';
	role: string | null;
	provider: string;
	external_identifier: string | null;
	auth_data: string | Record<string, unknown> | null;
	app_access: boolean;
	admin_access: boolean;
}

export default defineEndpoint((router, ctx) => {
	router.get('/', async (req, res) => {

    const {database: knex, emitter, services, getSchema} = ctx

    const phone_number = ""

    const user = await knex
			.select<User & { tfa_secret: string | null }>(
				'u.id',
				'u.first_name',
				'u.last_name',
				'u.email',
				'u.phone_number',
				'u.password',
				'u.status',
				'u.role',
				'r.admin_access',
				'r.app_access',
				'u.tfa_secret',
				'u.provider',
				'u.external_identifier',
				'u.auth_data'
			)
			.from('directus_users as u')
			.leftJoin('directus_roles as r', 'u.role', 'r.id')
			.where('u.phone_number', phone_number)
			.first();

      const tokenPayload = {
        id: user.id,
        role: user.role,
        app_access: user.app_access,
        admin_access: user.admin_access,
      };

      const accessToken = jwt.sign(
        tokenPayload,
        process.env['SECRET'] as string,
        {
          expiresIn: process.env['ACCESS_TOKEN_TTL'],
          issuer: 'directus',
        }
      );

      const refreshTokenExpiration = new Date(
        Date.now() + getMilliseconds(process.env['REFRESH_TOKEN_TTL'], 0)
      );
      // const refreshToken = nanoid(64);
      const refreshToken = nanoid(64);

      await knex('directus_sessions').insert({
        token: refreshToken,
        user: user.id,
        expires: refreshTokenExpiration,
        ip: req.accountability?.ip,
        user_agent: req.accountability?.userAgent,
        origin: req.accountability?.origin,
      });

  });
});

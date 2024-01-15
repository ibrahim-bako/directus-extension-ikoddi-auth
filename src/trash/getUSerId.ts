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
# directus-extension-ikoddi-auth

Ikoddi authentication with directus

## How to install

1. Clone ikoddi-auth project as `directus-extension-ikoddi-auth` folder

   ```sh
   git clone https://github.com/ibrahimbako/ikoddi-auth.git directus-extension-ikoddi-auth
   ```

2. Install dependencies and build project

   ```sh
   npm i
   npm run build
   ```

3. Add env variables

   ```
   IKODDI_AUTH_API_URL: "..."
   IKODDI_AUTH_API_KEY: "..."
   IKODDI_AUTH_GROUP_ID: "..."
   IKODDI_AUTH_OTP_APP_ID: "..."
   ```

4. Add `phone_number` field to `directus_user` collection

5. Restart directus

## Usage

`<phone-number>` must be a valid phone number with country code

#### Send OTP

```
POST http://directus-base_url.com/smsotp/send-otp
data {
   "phone_number": "<phone-number>"
}

result {
   "verification_key": "<verification-key>"
}
```

#### Verify OTP and Login

```
POST http://directus-base_url.com/smsotp/verify
data {
   "phone_number": "<phone-number>",
   "otp_code": "<otp-code>",
   "verification_key": "<verification-key>"
}

result {
   "access_token": "<access-token>",
   "refresh_token": "<refresh-token>",
   "expires": <number>,
   "id": "<user-id>"
}
```

## Contribute

Since I don't know all of the typing systems out there, I would greatly appreciate if you
would let me know how types for a language you know should look like, or even implement
the generation of types for that language yourself.

If you find an error or think somthing in the process of generating types for the current
languages is done in a dumb way, feel free to also open an issue.

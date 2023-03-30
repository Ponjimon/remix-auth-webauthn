import { redirect, type SessionStorage } from '@remix-run/server-runtime';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type VerifiedAuthenticationResponse,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  VerifiedRegistrationResponse,
} from '@simplewebauthn/server';
import {
  Strategy,
  type StrategyVerifyCallback,
  type AuthenticateOptions,
} from 'remix-auth';
import invariant from 'tiny-invariant';
import type {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorFuture,
  PublicKeyCredentialJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';

export type WebAuthnUser = {
  userID: string;
  userName: string;
};
export type AuthenticationMode = 'registration' | 'authentication';
export type WebAuthnStrategyRegistrationOptions = {
  mode: 'registration';
  userIdentifier: string;
  userDisplayName: string;
  registrationInfo: VerifiedRegistrationResponse['registrationInfo'];
};
export type WebAuthnStrategyAuthenticationOptions = {
  mode: 'authentication';
  userIdentifier: string;
  authenticationInfo: VerifiedAuthenticationResponse['authenticationInfo'];
};
export type WebAuthnStrategyVerifyParams =
  | WebAuthnStrategyRegistrationOptions
  | WebAuthnStrategyAuthenticationOptions;

export type GetUserCredentialsFunction = (
  email: string
) => Promise<AuthenticatorDevice[]>;
export type VerifyUserIdentifierFunction = (
  userIdentifier: string
) => Promise<boolean>;

export type WebAuthnStrategyOptions = {
  /**
   * The expected origin of the request.
   */
  expectedOrigin: string;

  /**
   * The expected Relying Party ID (RPID).
   */
  expectedRPID: string;

  /**
   * The path for the login endpoint.
   */
  loginPath: string;

  /**
   * The path for the registration endpoint.
   */
  registrationPath: string;

  /**
   * The form input name used to get the email address.
   * @default "email"
   */
  emailField?: string;

  /**
   * The form input name used to get the username.
   * @default "username"
   */
  userNameField?: string;

  /**
   * The session key used to identify the user.
   * @default "auth:userIdentifier"
   */
  sessionUserIdentifierKey?: string;

  /**
   * The session key used to store the user's credential options.
   * @default "auth:credentialOptions"
   */
  sessionCredentialOptionsKey?: string;

  /**
   * The number of seconds after which credentials will expire.
   * @default 60000
   */
  credentialsTimeout?: number;

  /**
   * A function to generate a user ID for registration.
   */
  generateUserId?: () => string | Promise<string>;

  /**
   * A function to retrieve existing credentials of a user.
   */
  getUserCredentials: GetUserCredentialsFunction;
};

export const SESSION_MAX_AGE = 60 * 60 * 24;

export class WebAuthnStrategy<User> extends Strategy<
  User,
  WebAuthnStrategyVerifyParams
> {
  name = 'webauthn';

  private readonly errors = {
    requiredEmail: 'Email is required.',
    requiredUsername: 'Username is required.',
    requiredOptions: 'Credential options are required.',
    invalidEmail: 'Email is invalid.',
    invalidOptions: 'Credential options are invalid.',
    unauthorizedCredential: 'No credential found for this user.',
    invalidRegistration: 'Registration failed.',
    invalidAuthentication: 'Authentication failed.',
  };

  private readonly expectedOrigin: string;
  private readonly expectedRPID: string;
  private readonly loginPath: string;
  private readonly registrationPath: string;
  private readonly emailField: string;
  private readonly usernameField: string;
  private readonly sessionUserIdentifierKey: string;
  private readonly sessionCredentialOptionsKey: string;
  private readonly credentialsTimeout: number;

  private readonly generateUserId: () => string | Promise<string>;
  private readonly getUserCredentials: GetUserCredentialsFunction;
  private readonly verifyUserIdentifer?: VerifyUserIdentifierFunction;

  constructor(
    options: WebAuthnStrategyOptions,
    verify: StrategyVerifyCallback<User, WebAuthnStrategyVerifyParams>,
    verifyUserIdentifier?: VerifyUserIdentifierFunction
  ) {
    super(verify);
    this.expectedOrigin = options.expectedOrigin;
    this.expectedRPID = options.expectedRPID;
    this.loginPath = options.loginPath;
    this.registrationPath = options.registrationPath;
    this.emailField = options.emailField ?? 'email';
    this.usernameField = options.userNameField ?? 'username';
    this.sessionUserIdentifierKey =
      options.sessionUserIdentifierKey ?? 'auth:userIdentifier';
    this.sessionCredentialOptionsKey =
      options.sessionCredentialOptionsKey ?? 'auth:credentialOptions';
    this.credentialsTimeout = options.credentialsTimeout ?? 60000;

    this.generateUserId =
      options.generateUserId ??
      (async () => {
        if (typeof crypto !== 'undefined') {
          // Assume edge runtime like CF Workers
          return crypto.randomUUID();
        }
        // Otherwise assume node runtime
        return (await import('node:crypto')).randomUUID();
      });
    this.getUserCredentials = options.getUserCredentials;
    this.verifyUserIdentifer = verifyUserIdentifier;
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    const url = new URL(request.url);
    const session = await sessionStorage.getSession(
      request.headers.get('Cookie')
    );
    const sessionUserIdentifier = session.get(this.sessionUserIdentifierKey) as
      | string
      | null;
    const sessionCredentialOptions = session.get(
      this.sessionCredentialOptionsKey
    ) as
      | PublicKeyCredentialCreationOptionsJSON
      | PublicKeyCredentialRequestOptionsJSON
      | null;

    let user: User | null = session.get(options.sessionKey) ?? null;

    try {
      if (!user) {
        invariant(options.successRedirect, 'Expected successRedirect');

        const formData = await request.formData();
        if (!sessionUserIdentifier && !sessionCredentialOptions) {
          // Generate Options
          const email = formData.get(this.emailField);

          invariant(
            email && typeof email === 'string',
            this.errors.requiredEmail
          );

          if (!this.validateEmail(email)) {
            throw new Error(this.errors.invalidEmail);
          }

          const userCredentials = await this.getUserCredentials(email);
          const existingCredentials =
            userCredentials.map<PublicKeyCredentialDescriptorFuture>(
              ({ credentialID }) => ({
                type: 'public-key',
                id: credentialID,
                // TODO: transports
              })
            );

          const credentialOptions =
            url.pathname === this.registrationPath
              ? generateRegistrationOptions({
                  rpID: this.expectedRPID,
                  rpName: this.expectedOrigin,
                  userID: await this.generateUserId(),
                  userName: email,
                  authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    requireResidentKey: true,
                    userVerification: 'required',
                    residentKey: 'required',
                  },
                  timeout: this.credentialsTimeout,
                  excludeCredentials: existingCredentials,
                })
              : url.pathname === this.loginPath
              ? generateAuthenticationOptions({
                  rpID: this.expectedRPID,
                  timeout: this.credentialsTimeout,
                  userVerification: 'required',
                  allowCredentials: existingCredentials,
                })
              : null;

          if (!credentialOptions) {
            throw new Error('Invalid path.');
          }

          session.set(this.sessionUserIdentifierKey, email);
          session.set(this.sessionCredentialOptionsKey, credentialOptions);
          session.unset(options.sessionErrorKey);

          throw redirect(options.successRedirect, {
            headers: {
              'Set-Cookie': await sessionStorage.commitSession(session),
            },
          });
        }

        if (sessionUserIdentifier && sessionCredentialOptions) {
          // Verify Credentials
          const credentialOptionsString = formData.get('options');

          invariant(
            credentialOptionsString &&
              typeof credentialOptionsString === 'string',
            this.errors.requiredOptions
          );

          let credentialOptions: PublicKeyCredentialJSON;

          try {
            credentialOptions = JSON.parse(credentialOptionsString);
          } catch (e) {
            throw new Error(this.errors.invalidOptions);
          }

          const isAuthentication = url.pathname === this.loginPath;
          const isRegistration = url.pathname === this.registrationPath;

          if (
            isRegistration &&
            this.isRegistrationResponse(credentialOptions)
          ) {
            const username = formData.get(this.usernameField);
            invariant(
              username && typeof username === 'string',
              this.errors.requiredUsername
            );

            const response = await verifyRegistrationResponse({
              response: credentialOptions,
              expectedChallenge: sessionCredentialOptions.challenge,
              expectedOrigin: this.expectedOrigin,
              expectedRPID: this.expectedRPID,
            });

            const { verified, registrationInfo } = response;

            if (!verified || !registrationInfo) {
              throw new Error(this.errors.invalidRegistration);
            }

            user = await this.verify({
              mode: 'registration',
              userIdentifier: sessionUserIdentifier,
              userDisplayName: username,
              registrationInfo,
            });
          }

          if (
            isAuthentication &&
            this.isAuthenticationResponse(credentialOptions)
          ) {
            const credentials = await this.getUserCredentials(
              sessionUserIdentifier
            );

            const credential = credentials.find(
              ({ credentialID }) =>
                new TextDecoder().decode(credentialID) === credentialOptions.id
            );

            if (!credential) {
              throw new Error(this.errors.unauthorizedCredential);
            }

            const response = await verifyAuthenticationResponse({
              response: credentialOptions,
              expectedChallenge: sessionCredentialOptions.challenge,
              expectedOrigin: this.expectedOrigin,
              expectedRPID: this.expectedRPID,
              authenticator: credential,
              advancedFIDOConfig: {
                userVerification: 'required',
              },
            });

            const { verified, authenticationInfo } = response;

            if (!verified || !authenticationInfo) {
              throw new Error(this.errors.invalidAuthentication);
            }

            user = await this.verify({
              mode: 'authentication',
              userIdentifier: sessionUserIdentifier,
              authenticationInfo,
            });
          }

          session.set(options.sessionKey, user);
          session.unset(this.sessionUserIdentifierKey);
          session.unset(this.sessionCredentialOptionsKey);
          session.unset(options.sessionErrorKey);

          if (!user) {
            session.unset(options.sessionKey);
            throw new Error('Unknown error.');
          }

          throw redirect(options.successRedirect, {
            headers: {
              'Set-Cookie': await sessionStorage.commitSession(session),
            },
          });
        }
      }
    } catch (error) {
      if (error instanceof Response && error.status === 302) {
        throw error;
      }

      if (error instanceof Error) {
        return await this.failure(
          error.message,
          request,
          sessionStorage,
          options,
          error
        );
      }

      return await this.failure(
        'Unknown Error',
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(error, null, 2))
      );
    }

    if (!user) {
      throw new Error('Unable to authenticate.');
    }

    return this.success(user, request, sessionStorage, options);
  }

  private validateEmail(email: unknown): email is string {
    return /.+@.+/u.test(email as string);
  }

  private isRegistrationResponse(
    options: unknown
  ): options is RegistrationResponseJSON {
    return (
      typeof options === 'object' &&
      options !== null &&
      'response' in options &&
      'attestationObject' in (options as RegistrationResponseJSON).response
    );
  }

  private isAuthenticationResponse(
    options: unknown
  ): options is AuthenticationResponseJSON {
    return (
      typeof options === 'object' &&
      options !== null &&
      'response' in options &&
      'authenticatorData' in (options as AuthenticationResponseJSON).response
    );
  }
}

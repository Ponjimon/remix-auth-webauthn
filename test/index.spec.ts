import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type VerifiedAuthenticationResponse,
  type VerifiedRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';
import { AuthorizationError } from 'remix-auth';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GetUserCredentialsFunction, WebAuthnStrategy } from '../src';
import {
  BASE_OPTIONS,
  HOST_URL,
  LOGIN_PATH,
  REGISTRATION_PATH,
  sessionStorage,
} from './utils';

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * Mocks
 */
export const { origin, hostname } = new URL('http://localhost:3000');
export const verify = vi.fn();
export const getUserCredentials = vi.fn<
  Parameters<GetUserCredentialsFunction>,
  ReturnType<GetUserCredentialsFunction>
>();
export const generateUserId = vi.fn();
export const email = 'example@example.com';
export const username = 'username';
export const credentialCreationOptions: PublicKeyCredentialCreationOptionsJSON =
  {
    rp: {
      id: hostname,
      name: origin,
    },
    user: {
      id: 'userId',
      name: email,
      displayName: email,
    },
    challenge: 'challenge',
    pubKeyCredParams: [],
    timeout: 60000,
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      userVerification: 'required',
      residentKey: 'required',
    },
  };
export const credentialRequestOptinons: PublicKeyCredentialRequestOptionsJSON =
  {
    challenge: 'challenge',
    timeout: 60000,
    rpId: hostname,
    allowCredentials: [],
    userVerification: 'required',
  };

vi.mock('@simplewebauthn/server', async () => {
  const mod = await vi.importActual<typeof import('@simplewebauthn/server')>(
    '@simplewebauthn/server'
  );
  return {
    ...mod,
    generateAuthenticationOptions: vi.fn(),
    generateRegistrationOptions: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
    verifyRegistrationResponse: vi.fn(),
  };
});

describe('WebAuthnStrategy', () => {
  it('should set the name to webauthn', () => {
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    expect(strategy.name).toBe('webauthn');
  });

  it('should throw an error on missing required successRedirect option', async () => {
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', 'example@example.com');

    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
      })
      .catch(error => error);

    expect(result).toEqual(
      new AuthorizationError('Invariant failed: Expected successRedirect')
    );
  });

  it('Should throw a an invariant error on empty email', async () => {
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', '');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(
      new AuthorizationError('Invariant failed: Email is required.')
    );
  });

  it('should throw an error on invalid form email', async () => {
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', 'invalid-email');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(new AuthorizationError('Email is invalid.'));
  });

  it('should get user credentials', async () => {
    const authenticatorList: AuthenticatorDevice[] = [
      {
        counter: 0,
        credentialID: new TextEncoder().encode('credentialID'),
        credentialPublicKey: new TextEncoder().encode('credentialPublicKey'),
      },
    ];
    getUserCredentials.mockImplementation(async () => authenticatorList);

    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', email);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(getUserCredentials).toHaveBeenCalledOnce();
    expect(getUserCredentials).toHaveReturnedWith(authenticatorList);
  });

  it('should generate userId', async () => {
    getUserCredentials.mockImplementation(async () => []);
    generateUserId.mockImplementationOnce(async () => 'userId');

    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
        generateUserId,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', 'example@example.com');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(generateUserId).toHaveBeenCalledOnce();
  });

  it('should generate registration credential options', async () => {
    getUserCredentials.mockImplementation(async () => []);
    generateUserId.mockImplementationOnce(async () => 'userId');

    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
        generateUserId,
      },
      verify
    );

    const email = 'example@example.com';
    const formData = new FormData();
    formData.append('email', email);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(generateRegistrationOptions).toHaveBeenCalledWith({
      rpID: hostname,
      rpName: origin,
      userID: 'userId',
      userName: email,
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        requireResidentKey: true,
        userVerification: 'required',
        residentKey: 'required',
      },
      timeout: 60000,
      excludeCredentials: [],
    });
  });

  it('should generate authentication credential options', async () => {
    getUserCredentials.mockImplementation(async () => []);
    generateUserId.mockImplementationOnce(async () => 'userId');

    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
        generateUserId,
      },
      verify
    );

    const email = 'example@example.com';
    const formData = new FormData();
    formData.append('email', email);

    const request = new Request(`${HOST_URL}${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(generateAuthenticationOptions).toHaveBeenCalledWith({
      rpID: hostname,
      timeout: 60000,
      userVerification: 'required',
      allowCredentials: [],
    });
  });

  it('should store email and options in session', async () => {
    getUserCredentials.mockImplementation(async () => []);
    generateUserId.mockImplementationOnce(async () => 'userId');

    vi.mocked(generateRegistrationOptions).mockImplementationOnce(
      () => credentialCreationOptions
    );

    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
        generateUserId,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', email);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    const result = (await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error)) as Response;

    const session = await sessionStorage.getSession(
      result.headers.get('Set-Cookie') ?? ''
    );

    expect(session.data['auth:userIdentifier']).toBe(email);
    expect(session.data['auth:credentialOptions']).toMatchObject(
      credentialCreationOptions
    );
    expect(session.data['auth:error']).toBeUndefined();
  });

  it('should throw a redirect on first first phase', async () => {
    getUserCredentials.mockImplementation(async () => []);
    generateUserId.mockImplementationOnce(async () => 'userId');

    vi.mocked(generateRegistrationOptions).mockImplementationOnce(
      () => credentialCreationOptions
    );

    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
        generateUserId,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', email);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    try {
      await strategy.authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      });
    } catch (error) {
      expect(error instanceof Response).toBe(true);
      expect(error.status).toBe(302);
    }
  });

  it('should throw an invariant error if there are no credential options', async () => {
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(
      new AuthorizationError(
        'Invariant failed: Credential options are required.'
      )
    );
  });

  it('should throw an error on non-json-parseable credential options', async () => {
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', '0{}');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(
      new AuthorizationError('Credential options are invalid.')
    );
  });

  it('should throw an invariant error on empty username', async () => {
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set(
      'options',
      JSON.stringify({
        id: 'id',
        rawId: 'rawId',
        response: {
          clientDataJSON: 'clientDataJSON',
          attestationObject: 'attestationObject',
        },
        type: 'public-key',
        clientExtensionResults: {},
      } as RegistrationResponseJSON)
    );

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(
      new AuthorizationError('Invariant failed: Username is required.')
    );
  });

  it('should call verifyRegistrationResponse', async () => {
    const registrationResponse: RegistrationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        attestationObject: 'attestationObject',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(registrationResponse));
    formData.set('username', 'username');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(verifyRegistrationResponse).toHaveBeenCalledWith({
      response: registrationResponse,
      expectedChallenge: credentialCreationOptions.challenge,
      expectedOrigin: origin,
      expectedRPID: hostname,
    });
  });

  it('should throw an error on faulty registration response', async () => {
    vi.mocked(verifyRegistrationResponse).mockImplementationOnce(async () => ({
      verified: false,
    }));
    const registrationResponse: RegistrationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        attestationObject: 'attestationObject',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(registrationResponse));
    formData.set('username', 'username');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(new AuthorizationError('Registration failed.'));
  });

  it('should call verify with mode `registration`', async () => {
    const registrationInfo: VerifiedRegistrationResponse['registrationInfo'] = {
      fmt: 'none' as const,
      counter: 0,
      aaguid: 'aaguid',
      credentialID: new TextEncoder().encode('credentialID'),
      credentialPublicKey: new TextEncoder().encode('credentialPublicKey'),
      credentialType: 'public-key' as const,
      attestationObject: new TextEncoder().encode('attestationObject'),
      userVerified: true,
      credentialDeviceType: 'singleDevice' as const,
      credentialBackedUp: false,
    };
    vi.mocked(verifyRegistrationResponse).mockImplementationOnce(async () => ({
      verified: true,
      registrationInfo,
    }));
    const registrationResponse: RegistrationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        attestationObject: 'attestationObject',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(registrationResponse));
    formData.set('username', username);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(verify).toHaveBeenCalledWith({
      mode: 'registration',
      userIdentifier: email,
      userDisplayName: username,
      registrationInfo,
    });
  });

  it('should properly set the session after successful registration', async () => {
    verify.mockImplementationOnce(async () => ({
      id: 'id',
    }));
    const registrationInfo: VerifiedRegistrationResponse['registrationInfo'] = {
      fmt: 'none' as const,
      counter: 0,
      aaguid: 'aaguid',
      credentialID: new TextEncoder().encode('credentialID'),
      credentialPublicKey: new TextEncoder().encode('credentialPublicKey'),
      credentialType: 'public-key' as const,
      attestationObject: new TextEncoder().encode('attestationObject'),
      userVerified: true,
      credentialDeviceType: 'singleDevice' as const,
      credentialBackedUp: false,
    };
    vi.mocked(verifyRegistrationResponse).mockImplementationOnce(async () => ({
      verified: true,
      registrationInfo,
    }));
    const registrationResponse: RegistrationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        attestationObject: 'attestationObject',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    let session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(registrationResponse));
    formData.set('username', username);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = (await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error)) as Response;

    session = await sessionStorage.getSession(
      result.headers.get('Set-Cookie') ?? ''
    );

    expect(session.data).toHaveProperty('user');
    expect(session.data['auth:userIdentifier']).toBeUndefined();
    expect(session.data['auth:credentialOptions']).toBeUndefined();
    expect(session.data['auth:error']).toBeUndefined();
  });

  it('should throw an error if it does not return a user', async () => {
    const registrationInfo: VerifiedRegistrationResponse['registrationInfo'] = {
      fmt: 'none' as const,
      counter: 0,
      aaguid: 'aaguid',
      credentialID: new TextEncoder().encode('credentialID'),
      credentialPublicKey: new TextEncoder().encode('credentialPublicKey'),
      credentialType: 'public-key' as const,
      attestationObject: new TextEncoder().encode('attestationObject'),
      userVerified: true,
      credentialDeviceType: 'singleDevice' as const,
      credentialBackedUp: false,
    };
    vi.mocked(verifyRegistrationResponse).mockImplementationOnce(async () => ({
      verified: true,
      registrationInfo,
    }));
    const registrationResponse: RegistrationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        attestationObject: 'attestationObject',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(registrationResponse));
    formData.set('username', username);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = (await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error)) as Response;

    expect(result).toEqual(new AuthorizationError('Unknown error.'));
  });

  it('should throw an error if credential is not found', async () => {
    getUserCredentials.mockImplementationOnce(async () => []);
    const authenticationResponse: AuthenticationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        authenticatorData: 'attestationObject',
        signature: 'signature',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(authenticationResponse));

    const request = new Request(`${HOST_URL}${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(
      new AuthorizationError('No credential found for this user.')
    );
  });

  it('should throw an error if credential is not found', async () => {
    const credential: AuthenticatorDevice = {
      credentialPublicKey: new TextEncoder().encode('publicKey'),
      credentialID: new TextEncoder().encode('id'),
      counter: 0,
    };
    getUserCredentials.mockImplementationOnce(async () => [credential]);
    const authenticationResponse: AuthenticationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        authenticatorData: 'attestationObject',
        signature: 'signature',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(authenticationResponse));

    const request = new Request(`${HOST_URL}${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(verifyAuthenticationResponse).toHaveBeenCalledWith({
      response: authenticationResponse,
      expectedChallenge: credentialCreationOptions.challenge,
      expectedOrigin: origin,
      expectedRPID: hostname,
      authenticator: credential,
      advancedFIDOConfig: {
        userVerification: 'required',
      },
    });
  });

  it('should throw an error on faulty authentication response', async () => {
    const credential: AuthenticatorDevice = {
      credentialPublicKey: new TextEncoder().encode('publicKey'),
      credentialID: new TextEncoder().encode('id'),
      counter: 0,
    };
    vi.mocked(verifyAuthenticationResponse).mockImplementationOnce(
      async () => ({
        verified: false,
        authenticationInfo: {
          credentialID: credential.credentialID,
          newCounter: 0,
          userVerified: false,
          credentialDeviceType: 'singleDevice' as const,
          credentialBackedUp: false,
        },
      })
    );
    getUserCredentials.mockImplementationOnce(async () => [credential]);
    const authenticationResponse: AuthenticationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        authenticatorData: 'attestationObject',
        signature: 'signature',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(authenticationResponse));

    const request = new Request(`${HOST_URL}${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(verifyAuthenticationResponse).toHaveBeenCalledWith({
      response: authenticationResponse,
      expectedChallenge: credentialCreationOptions.challenge,
      expectedOrigin: origin,
      expectedRPID: hostname,
      authenticator: credential,
      advancedFIDOConfig: {
        userVerification: 'required',
      },
    });
  });

  it('should call verify with mode `authentication`', async () => {
    const credential: AuthenticatorDevice = {
      credentialPublicKey: new TextEncoder().encode('publicKey'),
      credentialID: new TextEncoder().encode('id'),
      counter: 0,
    };
    const authenticationInfo: VerifiedAuthenticationResponse['authenticationInfo'] =
      {
        credentialID: credential.credentialID,
        newCounter: 1,
        userVerified: false,
        credentialDeviceType: 'singleDevice' as const,
        credentialBackedUp: false,
      };
    vi.mocked(verifyAuthenticationResponse).mockImplementationOnce(
      async () => ({
        verified: true,
        authenticationInfo,
      })
    );
    getUserCredentials.mockImplementationOnce(async () => [credential]);
    const authenticationResponse: AuthenticationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        authenticatorData: 'attestationObject',
        signature: 'signature',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    const session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(authenticationResponse));

    const request = new Request(`${HOST_URL}${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(verify).toHaveBeenCalledWith({
      mode: 'authentication',
      userIdentifier: email,
      authenticationInfo,
    });
  });

  it('should properly set the session after successful authentication', async () => {
    verify.mockImplementationOnce(async () => ({
      id: 'id',
    }));
    const credential: AuthenticatorDevice = {
      credentialPublicKey: new TextEncoder().encode('publicKey'),
      credentialID: new TextEncoder().encode('id'),
      counter: 0,
    };
    const authenticationInfo: VerifiedAuthenticationResponse['authenticationInfo'] =
      {
        credentialID: credential.credentialID,
        newCounter: 1,
        userVerified: false,
        credentialDeviceType: 'singleDevice' as const,
        credentialBackedUp: false,
      };
    vi.mocked(verifyAuthenticationResponse).mockImplementationOnce(
      async () => ({
        verified: true,
        authenticationInfo,
      })
    );
    getUserCredentials.mockImplementationOnce(async () => [credential]);
    const authenticationResponse: AuthenticationResponseJSON = {
      id: 'id',
      rawId: 'rawId',
      response: {
        clientDataJSON: 'clientDataJSON',
        authenticatorData: 'attestationObject',
        signature: 'signature',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );
    let session = await sessionStorage.getSession();
    session.set('auth:userIdentifier', email);
    session.set('auth:credentialOptions', credentialCreationOptions);

    const formData = new FormData();
    formData.set('options', JSON.stringify(authenticationResponse));

    const request = new Request(`${HOST_URL}${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
        cookie: await sessionStorage.commitSession(session),
      },
      body: formData,
    });

    const result = (await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error)) as Response;

    session = await sessionStorage.getSession(
      result.headers.get('Set-Cookie') ?? ''
    );

    expect(session.data).toHaveProperty('user');
    expect(session.data['auth:userIdentifier']).toBeUndefined();
    expect(session.data['auth:credentialOptions']).toBeUndefined();
    expect(session.data['auth:error']).toBeUndefined();
  });

  it('should throw an invalid path error', async () => {
    getUserCredentials.mockImplementation(async () => []);
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', email);

    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(new AuthorizationError('Invalid path.'));
  });

  it('should throw an unknown error', async () => {
    getUserCredentials.mockImplementationOnce(async () => {
      throw 'something';
    });
    const strategy = new WebAuthnStrategy(
      {
        loginPath: LOGIN_PATH,
        registrationPath: REGISTRATION_PATH,
        expectedOrigin: origin,
        expectedRPID: hostname,
        getUserCredentials,
      },
      verify
    );

    const formData = new FormData();
    formData.append('email', email);

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
    });

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(new AuthorizationError('Unknown Error'));
  });
});

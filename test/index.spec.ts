import { AuthorizationError } from 'remix-auth';
import { beforeEach } from 'vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WebAuthnStrategy } from '../src';
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
export const getUserCredentials = vi.fn();

describe('Basics', () => {
  it('Should contain the name of the Strategy', () => {
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

  it('Should throw an error on missing required successRedirect option', async () => {
    const formData = new FormData();
    formData.append('email', 'example@example.com');

    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
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
});

describe('Registration', () => {
  beforeEach(() => {});

  it('Should throw a an error on empty email', async () => {
    const formData = new FormData();
    formData.append('email', '');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
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

  it('Should throw an error on invalid form email', async () => {
    const formData = new FormData();
    formData.append('email', 'invalid-email');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
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

    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(result).toEqual(new AuthorizationError('Email is invalid.'));
  });

  it('Should get user credentials and call its function', async () => {
    getUserCredentials.mockImplementation(async () => []);
    const formData = new FormData();
    formData.append('email', 'example@example.com');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
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

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);

    expect(getUserCredentials).toHaveBeenCalledOnce();
  });

  it.only('should generate registration options', async () => {
    getUserCredentials.mockImplementation(async () => []);

    const formData = new FormData();
    formData.append('email', 'example@example.com');

    const request = new Request(`${HOST_URL}${REGISTRATION_PATH}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
      body: formData,
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

    await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch(error => error);
  });
});

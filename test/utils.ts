import type { AuthenticateOptions } from 'remix-auth';
import { createCookieSessionStorage } from '@remix-run/node';
import { WebAuthnStrategy } from '../src';

/**
 * Constants
 */
export const SECRET_ENV = 'SECRET';
export const HOST_URL = 'http://localhost:3000';
export const LOGIN_PATH = '/login';
export const REGISTRATION_PATH = '/registration';

/**
 * Strategy Instance Defaults
 */
export const BASE_OPTIONS: AuthenticateOptions = {
  name: 'webauthn',
  sessionKey: 'user',
  sessionErrorKey: 'error',
  sessionStrategyKey: 'strategy',
};

/**
 * Session Storage.
 */
export const sessionStorage = createCookieSessionStorage({
  cookie: { secrets: ['SESSION_SECRET_KEY'] },
});

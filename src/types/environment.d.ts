declare global {
  namespace NodeJS {
    interface ProcessEnv {
      DATABASE_URL: string;
      SECRET_KEY: string;
      SECRET_COOKIE: string;
      IMAGE_URL: string;
      BCRYPT_SALT: string;
    }
  }
}
export {};

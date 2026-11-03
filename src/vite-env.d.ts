/// <reference types="vite/client" />

declare module "*.css";
declare module "*.svg";
declare module "*.png";

/** 构建期由 vite.config.ts 的 define 注入，来自 package.json 的 version。 */
declare const __APP_VERSION__: string;

import { SetMetadata } from "@nestjs/common";
import { metadata } from "reflect-metadata/no-conflict"

export const PUBLIC_KEY = 'isPublic';

export const IsPublic = () => SetMetadata(PUBLIC_KEY, true)

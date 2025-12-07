import { SetMetadata } from "@nestjs/common";
import { metadata } from "reflect-metadata/no-conflict"

export const ROLE_KEY = 'roles';

export const Role = (data: string[]) =>  SetMetadata(ROLE_KEY, data);
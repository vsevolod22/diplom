import { Module } from '@nestjs/common';
import { OciResolver } from './oci-resolver.js';

@Module({ providers: [OciResolver], exports: [OciResolver] })
export class OciModule {}

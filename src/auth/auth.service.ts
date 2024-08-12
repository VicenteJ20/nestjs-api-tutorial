import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) { }

  async signin(dto: AuthDto) {

    try {
      const user = await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      })

      if (!user) {
        throw new ForbiddenException('Credenciales incorrectas')
      }

      const validPassword = await argon.verify(user.passwordHash, dto.password)

      if (!validPassword) {
        throw new ForbiddenException('Credenciales incorrectas')
      }

      return this.signToken(user.id, user.email, user.name)
    } catch (error) {
      throw new ForbiddenException('Credenciales incorrectas')
    }
  }
  async signup(dto: AuthDto) {
    const hash = await argon.hash(dto.password);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          passwordHash: hash,
          name: dto.name,
        },
      })

      return this.signToken(user.id, user.email, user.name)
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('El correo ya está en uso')
        }
      }

      throw error
    }
  }

  async signToken(userId: string, email: string, name: string): Promise<{access_token: string}> {
    const payload = {
      sub: userId,
      email,
      name,
    }

    const secret = this.config.get('SECRET_KEY')

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '1d',
      secret: secret
    }) as string

    return {
      access_token: token
    }
  }
}

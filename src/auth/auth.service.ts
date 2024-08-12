import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

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

      delete user.passwordHash
      return user
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
  
      return user 
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('El correo ya está en uso')
        }
      }

      throw error
    }
  } 
}

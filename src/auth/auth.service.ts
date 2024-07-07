import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthRepository } from './auth.repository';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { error } from 'console';

@Injectable()
export class AuthService implements AuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  async signUp(dto: AuthDto) {
    try {
      // generate password with hash
      const password = await argon.hash(dto.password);
      // save to db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password,
        },
      });

      // delete user password from response
      delete user.password;

      // return the user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials already taken');
        }
      }

      throw error;
    }
  }

  async signIn(dto: AuthDto) {
    // get the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if the email doesnt exist
    if (!user) throw new ForbiddenException('Credential incorrect');

    const pwMatches = await argon.verify(user.password, dto.password);

    if (!pwMatches) throw new ForbiddenException('Credential incorrect');

    // delete password from the response and returning user.
    delete user.password;
    return user;
  }
}

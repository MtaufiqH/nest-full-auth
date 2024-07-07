import { Controller, Get, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { getUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guard';

@Controller('users')
@UseGuards(JwtGuard) // all the endpoint below this controller will use the guard
export class UserController {
    @Get('me')
    getMe(@getUser() user: User){
        return user
    }
}

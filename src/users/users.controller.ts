import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { User } from './schema/user.schema';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}
  @Post()
  async createUser(@Body() request: CreateUserDto) {
    return this.usersService.create(request);
  }
  @Get()
  @UseGuards(JwtAuthGuard)
  async getUsers(@CurrentUser() currentUser: User) {
    console.log('User: ', currentUser);
    return this.usersService.getUsers();
  }
}

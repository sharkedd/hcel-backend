// src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login-dto';
import { RpcException } from '@nestjs/microservices';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(LoginDto: LoginDto) {
    const { email, password: pass } = LoginDto;
    const user = await this.usersService.findByEmail(email);
    if (!user)
      throw new RpcException({ status: 404, message: 'Usuario no encontrado' });

    const isPasswordValid = await bcrypt.compare(pass, user.password);
    if (!isPasswordValid) {
      console.error('❌ Contraseña incorrecta para el usuario:', email);
      throw new RpcException({ status: 401, message: 'Contraseña incorrecta' });
    }

    // devolvemos el usuario sin la contraseña
    const { password, ...result } = user.toObject();
    return result;
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user._id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}

import { Body, Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login-dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern({ cmd: 'login_user' })
  async login(@Payload() loginDto: LoginDto) {
    const user = await this.authService.validateUser(loginDto);
    return this.authService.login(user);
  }

  @MessagePattern({ cmd: 'validate_token' })
  async validateToken(@Payload() token: string) {
    console.log('🛡️ Validando token recibido:', token);
    return this.authService.validateToken(token);
  }
}

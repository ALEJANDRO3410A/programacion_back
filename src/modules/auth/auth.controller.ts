import { Body, Controller, Post, Query } from '@nestjs/common';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { AuthService } from './auth.service';
import { ApiTags } from '@nestjs/swagger';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    registerUser(@Body() userObj: RegisterAuthDto) {
        console.log(userObj);
        return this.authService.funRegister(userObj);
    }

    @Post('login')
    login(@Body() credenciales: LoginAuthDto) {
        return this.authService.login(credenciales);
    }

    @Post('forgot-password')
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
        return this.authService.forgotPassword(forgotPasswordDto.email);
    }

    @Post('reset-password')
    async resetPassword(
        @Query('token') token: string, 
        @Body() body: { newPassword: string }) {
        return this.authService.resetPassword(token, body.newPassword);
    }
}

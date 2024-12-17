import { Injectable, HttpException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity';
import { Repository } from 'typeorm';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { hash, compare } from 'bcrypt';
import * as nodemailer from 'nodemailer';
import * as dotenv from 'dotenv';

dotenv.config();

@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        @InjectRepository(User) private readonly userRepository: Repository<User>,
    ) {}

    async funRegister(objUser: RegisterAuthDto) {
        const { password } = objUser;
        const hashedPassword = await hash(password, 12);
        objUser = { ...objUser, password: hashedPassword };
        return this.userRepository.save(objUser);
    }

    async login(credenciales: LoginAuthDto) {
        const { email, password } = credenciales;
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) throw new HttpException('Usuario no encontrado', 404);

        const verificarPass = await compare(password, user.password);
        if (!verificarPass) throw new HttpException('Contraseña Inválida', 401);

        const payload = { email: user.email, id: user.id };
        const token = this.jwtService.sign(payload);
        return { user, token };
    }

    async forgotPassword(email: string) {
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) throw new HttpException('Usuario no encontrado', 404);

        const token = this.jwtService.sign({ email: user.email }, { expiresIn: '1h' });
        const resetLink = `http://localhost:4200/auth/reset-password?token=${token}`;

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_APP_PASSWORD,
            },
        });

        const mailOptions = {
            from: process.env.GMAIL_USER,
            to: email,
            subject: 'Restablecer Contraseña',
            text: `Haz clic en el siguiente enlace para restablecer tu contraseña: ${resetLink}`,
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log('Correo enviado');
        } catch (error) {
            console.error('Error al enviar el correo:', error);
            throw new HttpException('Error al enviar el correo', 500);
        }

        return { message: 'Enlace de restablecimiento enviado', resetLink };
    }

    async resetPassword(token: string, newPassword: string) {
        try {
            const decoded = this.jwtService.verify(token);
            const userEmail = decoded.email;

            const user = await this.userRepository.findOne({ where: { email: userEmail } });
            if (!user) throw new HttpException('Usuario no encontrado', 404);

            const hashedPassword = await hash(newPassword, 12);
            await this.userRepository.update({ email: userEmail }, { password: hashedPassword });

            return { message: 'Contraseña actualizada con éxito.' };
        } catch (error) {
            throw new HttpException('Token no válido o expirado', 401);
        }
    }
}

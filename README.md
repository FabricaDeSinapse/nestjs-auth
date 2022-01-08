# NestJS - Autenticação e Autorização com JWT

## Tópicos

[TOC]

## Prisma

### Instalar o prisma

```bash
npm install prisma -D
```

### Inicializar o prisma

```bash
npx prisma init
```

### `prisma/schema.prisma`

```java
// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

datasource db {
  provider = "sqlite"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id Int @id @default(autoincrement())

  email    String @unique
  password String

  name String
}
```

## Arquivo `.env`

```bash
# Configuration

JWT_SECRET=""

# Database

DATABASE_URL=""
```

### Arquivo `.env` preenchido

```bash
# Configuration

JWT_SECRET="texto aleatório para proteger sua aplicação"

# Database

DATABASE_URL="file:./sqlite.db"
```

## Migrar o banco

```bash
npx prisma migrate dev --name init
```

Esse comando deverá instalar a dependência `@prisma/client` no projeto.

### Criação do módulo do prisma

#### Comandos na CLI para criação dos arquivos

```bash
nest g module prisma
nest g service prisma
```

#### Conteúdo dos arquivos

##### `src/prima/prisma.module.ts`

```typescript
import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
```

##### `src/prisma/prisma.service.ts`

```typescript
import { INestApplication, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
  }

  async enableShutdownHooks(app: INestApplication) {
    this.$on('beforeExit', async () => {
      await app.close();
    });
  }
}
```

## Dependências

- `@nestjs/passport`
- `@nestjs/jwt`
- `bcrypt`
- `class-validator`
- `class-transformer`
- `passport`
- `passport-jwt`

Atalho para instalar tudo ao mesmo tempo:

```bash
npm i @nestjs/passport @nestjs/jwt bcrypt passport passport-jwt
```

## Dependências Dev

- `@types/passport-jwt`
- `@types/bcrypt`

```bash
npm i -D @types/passport-jwt @types/bcrypt
```

## Códigos

### Domain/Autorização: diretório `user`

#### Comandos na CLI para criação dos arquivos

```bash
nest g resource user
```

#### `user/user.entity.ts`

```typescript
export class User {
  id?: number;
  email: string;
  password: string;
  name: string;
}
```

#### `user/create-user.dto.ts`

```typescript
import { User } from '../entities/user.entity';
import {
  IsEmail,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateUserDto extends User {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(4)
  @MaxLength(20)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'password too weak',
  })
  password: string;

  @IsString()
  name: string;
}
```

#### `user/user.controller.ts`

```typescript
import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }
}
```

#### `user/user.service.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const data: Prisma.UserCreateInput = {
      ...createUserDto,
      password: await bcrypt.hash(createUserDto.password, 10),
    };

    const createdUser = await this.prisma.user.create({ data });

    return {
      ...createdUser,
      password: undefined,
    };
  }

  findById(id: number) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }
}
```

### `user/user.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
```

### Autenticação: diretório `auth`

```bash
nest g module auth
nest g controller auth
nest g service auth
```

#### `auth/auth.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UserModule } from '../user/user.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UserModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '30d' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}
```

#### `auth/auth.controller.ts`

```typescript
import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginRequestBody } from './model/LoginRequestBody';
import { IsPublic } from './public.decorator';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() { email, password }: LoginRequestBody) {
    return this.authService.login(email, password);
  }
}
```

#### `auth/auth.service.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UnauthorizedError } from '../errors/UnauthorizedError';
import { User } from '../user/entities/user.entity';
import { UserService } from '../user/user.service';
import { UserPayload } from './model/UserPayload';
import { UserToken } from './model/UserToken';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  async login(email: string, password: string): Promise<UserToken> {
    const user: User = await this.validateUser(email, password);

    const payload: UserPayload = {
      username: user.email,
      sub: user.id,
    };

    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  private async validateUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);

    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        return {
          ...user,
          password: undefined,
        };
      }
    }

    throw new UnauthorizedError(
      'Email address or password provided is incorrect.',
    );
  }
}
```

#### `auth/jwt.strategy.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserFromJwt } from './model/UserFromJwt';
import { UserPayload } from './model/UserPayload';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: UserPayload): Promise<UserFromJwt> {
    return { id: payload.sub, email: payload.username };
  }
}
```

#### `auth/jwt-auth.guard.ts`

```typescript
// NestJS
import { ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
// Password
import { AuthGuard } from '@nestjs/passport';
// RxJs
import { of } from 'rxjs';
import { map, mergeMap, takeWhile, tap } from 'rxjs/operators';
// Services
import { UserService } from '../user/user.service';
import { AuthRequest } from './model/AuthRequest';
// Models
import { UserFromJwt } from './model/UserFromJwt';
// Decorators
import { IS_PUBLIC_KEY } from './public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private reflector: Reflector,
    @Inject(UserService) private readonly userService: UserService,
  ) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const canActivate = super.canActivate(context);

    if (typeof canActivate === 'boolean') {
      return canActivate;
    }

    return of(canActivate).pipe(
      mergeMap((value) => value),
      takeWhile((value) => value),
      map(() => context.switchToHttp().getRequest<AuthRequest>()),
      mergeMap((request) =>
        of(request).pipe(
          map((req) => {
            if (!req.user) {
              throw Error('User was not found in request.');
            }

            return req.user;
          }),
          mergeMap((userFromJwt: UserFromJwt) =>
            this.userService.findById(userFromJwt.id),
          ),
          tap((user) => {
            request.principal = user;
          }),
        ),
      ),
      map((user) => Boolean(user)),
    );
  }
}
```

#### Importando tudo no `AppModule`

```typescript
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/jwt-auth.guard';
import { PrismaModule } from './prisma/prisma.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [PrismaModule, UserModule, AuthModule],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
})
export class AppModule {}
```

#### Diretório `auth/model`

##### `auth/model/UserFromJwt.ts`

```typescript
import { User } from '../../user/entities/user.entity';

export type UserFromJwt = Partial<User>;
```

##### `auth/model/UserPayload.ts`

```typescript
export interface UserPayload {
    username: string;
    sub: number;
}
```

##### `auth/model/UserToken.ts`

```typescript
export interface UserToken {
    access_token: string;
}
```

##### `auth/model/AuthRequest.ts`

```typescript
import { Request } from 'express';
import { User } from '../../domain/user/entities/user.entity';

export interface AuthRequest extends Request {
    principal: User;
}
```

##### `auth/model/LoginRequestBody.ts`

```typescript
import {
  IsEmail,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class LoginRequestBody {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(4)
  @MaxLength(20)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'password too weak',
  })
  password: string;
}
```

### Decorators

#### `auth/public.decorator.ts`

```typescript
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

#### `auth/current-user.decorator.ts`

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from 'src/user/entities/user.entity';
import { AuthRequest } from './model/AuthRequest';

export const CurrentUser = createParamDecorator(
  (data: unknown, context: ExecutionContext): User => {
    const request = context.switchToHttp().getRequest<AuthRequest>();

    return request.principal;
  },
);
```

### Tratamento de erros: diretório `errors`

#### `src/errors/unauthorized.error.ts`

```typescript
export class UnauthorizedError extends Error {}
```

### Tratamento de erros: diretório `interpcetor`

#### `src/interceptors/unauthorized.interceptor.ts`

```typescript
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { UnauthorizedError } from '../errors/UnauthorizedError';

@Injectable()
export class UnauthorizedInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((error) => {
        if (error instanceof UnauthorizedError) {
          throw new UnauthorizedException(error.message);
        } else {
          throw error;
        }
      }),
    );
  }
}
```

### Ativando validação e interceptor no `main.ts`

```typescript
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { UnauthorizedInterceptor } from './interceptors/unauthorized.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Pipes
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Interceptors
  app.useGlobalInterceptors(new UnauthorizedInterceptor());

  await app.listen(3000);
}

bootstrap();
```

## Requisições

Para criar um usuário, certifique-se de liberar o endpoint antes com o `decorator` `@IsPublic()`.

Caso a criação de usuários da sua aplicação seja restrita, remova o `decorator` `IsPublic()`, pois as próximas criações deverão ser autenticadas por um usuário já existente.

```json
Endpoint: /user
Method: POST

Request Body:
{
	"email": "paulo@salvatore.tech",
	"password": "Ab12",
    "name": "Paulo Salvatore"
}

Response Body (201):
{
    "id": 1,
	"email": "paulo@salvatore.tech",
    "name": "Paulo Salvatore"
}
```

```json
Endpoint: /login
Method: POST

Request Body:
{
	"email": "paulo@salvatore.tech",
	"password": "Ab12"
}

Response Body (200):
{
    "access_token": "JWT token gerado"
}
```

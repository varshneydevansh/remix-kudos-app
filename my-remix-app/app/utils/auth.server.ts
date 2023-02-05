// app/utils/auth.server.ts
import type { RegisterForm, LoginForm } from './types.server'
import {prisma} from './prisma.server'
import {json, createCookieSessionStorage, redirect} from '@remix-run/node'
import { createUser } from './user.server'
import bcrypt from 'bcryptjs';

const secret = process.env.SESSION_SECRET;
if(!secret)
{
  throw new Error("Session_SECRET is not set");
}
const storageCookieBucket = createCookieSessionStorage({
  cookie: {
    name: "kudos-session",
    secure: process.env.NODE_ENV === "production",
    secrets: [secret],
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: true
  }
})


export async function register(user: RegisterForm) {
    const exists = await prisma.user.count({where: {email: user.email} })
    if(exists)
    {
        return json({error: 'User already exists with the email'} , {status: 400})
    }

    const newUser = await createUser(user)
    if (!newUser) {
      return json(
        {
          error: `Something went wrong trying to create a new user.`,
          fields: { email: user.email, password: user.password },
        },
        { status: 400 },
      );
    }

    return createUserSession(newUser.id, '/');
};

export const login = async (form: LoginForm) => {
  
  const user = await prisma.user.findUnique({
    where: {email: form.email}
  });

  if(!user || !(await bcrypt.compare(form.password, user.password)) )
  {
    return json({error: 'Incorrect Login' }, {status: 400});
  }

  return createUserSession(user.id, '/');
}

export const createUserSession =async (userID: string, redirectTo: string) => {
  const session = await storageCookieBucket.getSession();
  session.set('userID', userID)

  return redirect(redirectTo, {headers:{
    "Set-Cookie": await storageCookieBucket.commitSession(session)
  }})
}

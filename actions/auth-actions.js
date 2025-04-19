"use server";

import { createAuthSession, destroySession } from "@/lib/auth";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { createUser, getUserByEmail } from "@/lib/user";
import { redirect } from "next/navigation";

export async function signup(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  let errors = {};
  // store it in database(create a new user)
  if (!email.includes("@")) {
    errors.email = "Please enter a valid email address.";
  }
  if (password.trim().length < 8) {
    errors.password = "Password must be atleast 8 characters long.";
  }
  if (Object.keys(errors).length > 0) {
    return {
      errors,
    };
  }
  const hashedPassword = hashUserPassword(password);
  try {
    const id = createUser(email, hashedPassword);
    await createAuthSession(id);
    redirect("/training");
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return {
        errors: {
          email: "It seems like your account for the choosen email already exist",
        },
      };
    }
    throw error;
  }
}
export async function login(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  const existingUser = getUserByEmail(email);
  const isValidPassword=verifyPassword(existingUser.password,password);
  if(!isValidPassword)
    return {
      errors: {
        email: "could not aauthenticate user,please check your credentials",
      },
    };
    await createAuthSession(existingUser.id);
    redirect("/training");
}
export async function auth(mode,prevState,formData) {
  if(mode==='login'){
    return login(prevState,formData);
  }
  return signup(prevState,formData);
}
export async function logout() {
  await destroySession();
  redirect('/')
}
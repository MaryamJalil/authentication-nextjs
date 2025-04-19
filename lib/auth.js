import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import { Lucia } from "lucia";
import db from "./db";
import { cookies } from "next/headers";

const adapter = new BetterSqlite3Adapter(db, {
  user: "users",
  session: "sessions",
});
const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
});
export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  (await cookies()).set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
}
export async function verifyAuth() {
  const sessionCookie=(await cookies()).get(lucia.sessionCookieName)
  if (!sessionCookie) {
    return {
      user: null,
      session: null,
    };
  }
  const sessionId = sessionCookie.value;
  if (!sessionId) {
    return {
      user: null,
      session: null,
    };
  }
 const  result=lucia.validateSession(sessionId);
 try{
    if((await result).session && (await result).session.fresh){
        const sessionCookie=lucia.createSessionCookie((await result).session.id);
        (await cookies()).set(
            sessionCookie.name,
            sessionCookie.value,
            sessionCookie.attributes
          );
    
     }
     if(!(await result).session){
        const sessionCookie=lucia.createBlankSessionCookie();
        (await cookies()).set(
                sessionCookie.name,
            sessionCookie.value,
            sessionCookie.attributes 
        )
     }
 }
 catch{

 }

return result;
}

export async function destroySession() {
  const {session}=await verifyAuth();
  if(!session){
    return {
      error:'unauthorized!'
    }
  }
await lucia.invalidateSession(session.id);
const sessionCookie=lucia.createBlankSessionCookie();
(await cookies()).set(
        sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes 
)

}
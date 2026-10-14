// Request input for Next.js (same contract as standard_blocks.input): every body and query goes through a declared
// strict Zod schema; unknown fields refused, a bounded body read once, repeated query parameters refused.
//
//   const OrderIn = z.object({ item: z.string().max(100), quantity: z.number().int().min(1) }).strict();
//   const order = await body(request, OrderIn);
import { HttpError } from "./session.js";

export const MAX_BODY = 1_000_000;

export function strict(schema) {
  const def = schema?._def;
  // Zod 3: unknownKeys "strict"; Zod 4: catchall never
  return Boolean(def && (def.unknownKeys === "strict" || def.catchall?._def?.typeName === "ZodNever" ||
    def.catchall?._zod?.def?.type === "never" || def.catchall?.def?.type === "never"));
}

function validate(schema, data) {
  if (!strict(schema)) throw new Error("input schemas are strict: z.object({...}).strict()");
  const r = schema.safeParse(data);
  if (!r.success) {
    const issues = (r.error?.issues || []).slice(0, 20).map((i) => ({ path: i.path, code: i.code }));
    throw new HttpError(422, JSON.stringify({ invalid: issues }));
  }
  return r.data;
}

export async function body(request, schema, { maxBytes = MAX_BODY } = {}) {
  if (!(request.headers.get("content-type") || "").startsWith("application/json")) throw new HttpError(415, "application/json only");
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > maxBytes) throw new HttpError(413, "body too large");
  const reader = request.body?.getReader();
  const chunks = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) { await reader.cancel(); throw new HttpError(413, "body too large"); }
      chunks.push(value);
    }
  }
  let data;
  try { data = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new HttpError(400, "invalid JSON"); }
  return validate(schema, data);
}

export function query(request, schema) {
  const params = new URL(request.url).searchParams;
  const keys = [...params.keys()];
  if (new Set(keys).size !== keys.length) throw new HttpError(400, "a parameter appears twice");
  return validate(schema, Object.fromEntries(params));
}

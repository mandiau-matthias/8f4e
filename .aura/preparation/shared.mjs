const enc = new TextEncoder();
export async function hash(value, algorithm = 'SHA-256') {
  return [...new Uint8Array(await crypto.subtle.digest(algorithm, typeof value === 'string' ? enc.encode(value) : value))]
    .map(n => n.toString(16).padStart(2, '0')).join('');
}
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const concat = chunks => {
  const result = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0; for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; } return result;
};
export async function gitHash(type, content) {
  const data = typeof content === 'string' ? enc.encode(content) : content;
  return hash(concat([enc.encode(`${type} ${data.length}\0`), data]), 'SHA-1');
}

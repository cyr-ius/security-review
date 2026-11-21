// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import { ValidationPipe } from '@nestjs/common';

export async function findUser(prisma: any, dataSource: any, name: string, sort: string) {
  // ruleid: secreview.ts.prisma-raw-unsafe
  await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
  // ruleid: secreview.ts.prisma-raw-unsafe
  await prisma.$executeRawUnsafe('DELETE FROM users WHERE name = ' + name);
  // ok: secreview.ts.prisma-raw-unsafe
  await prisma.$queryRawUnsafe('SELECT * FROM users WHERE name = $1', name);
  // ok: secreview.ts.prisma-raw-unsafe
  await prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`;

  // ruleid: secreview.ts.typeorm-query-template
  await dataSource.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ruleid: secreview.ts.typeorm-query-template
  await dataSource.query("SELECT * FROM users WHERE name = '" + name + "'");
  // ok: secreview.ts.typeorm-query-template
  await dataSource.query('SELECT * FROM users WHERE name = $1', [name]);
  const qb = dataSource.getRepository('User').createQueryBuilder('user');
  // ruleid: secreview.ts.typeorm-query-template
  qb.where(`user.name = '${name}'`);
  // ruleid: secreview.ts.typeorm-query-template
  qb.orderBy('user.' + sort);
  // ok: secreview.ts.typeorm-query-template
  qb.where('user.name = :name', { name });
  return qb.getMany();
}

export function pipes() {
  // ruleid: secreview.ts.nest-validation-pipe-not-whitelisted
  const loose = new ValidationPipe();
  // ruleid: secreview.ts.nest-validation-pipe-not-whitelisted
  const transform = new ValidationPipe({ transform: true });
  // ok: secreview.ts.nest-validation-pipe-not-whitelisted
  const strict = new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true });
  return [loose, transform, strict];
}

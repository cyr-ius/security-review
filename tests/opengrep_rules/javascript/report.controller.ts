// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import { Body, Controller, Get, Param, Query } from '@nestjs/common';
import { exec } from 'node:child_process';
import { DataSource } from 'typeorm';

@Controller('reports')
export class ReportController {
  constructor(private readonly dataSource: DataSource) {}

  @Get(':id')
  async find(@Param('id') id: string, @Query('sort') sort: string) {
    // ruleid: secreview.js.taint-sql
    return this.dataSource.query(`SELECT * FROM report WHERE id = ${id} ORDER BY ${sort}`);
  }

  @Get()
  async list(@Query('owner') owner: string) {
    // ok: secreview.js.taint-sql
    return this.dataSource.query('SELECT * FROM report WHERE owner = $1', [owner]);
  }

  @Get('export')
  export(@Body() body: { format: string }) {
    // ruleid: secreview.js.taint-command
    exec(`convert report.pdf report.${body.format}`);
  }

  @Get('clone')
  clone(@Query('branch') branch: string) {
    const cp = require('node:child_process');
    // ruleid: secreview.js.taint-argument-injection
    cp.execFile('git', ['clone', '--branch', branch, 'https://example.com/repo']);
    // ok: secreview.js.taint-argument-injection
    cp.execFile('git', ['clone', '--branch', 'main', 'https://example.com/repo']);
    // ok: secreview.js.taint-argument-injection
    cp.execFile('git', ['clone', '--', branch, 'https://example.com/repo']);
  }

  @Get('view')
  view(@Query('name') name: string, @Res() res: any) {
    // ruleid: secreview.js.taint-view-injection
    res.render(name);
    // ok: secreview.js.taint-view-injection
    res.render('pages/home');
  }

  internal(format: string) {
    // ok: secreview.js.taint-command
    exec(`convert report.pdf report.${format}`);
  }
}

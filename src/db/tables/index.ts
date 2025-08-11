// src/db/tables/index.ts

import { createUsersTable } from './users';
import { createDeviceBindingsTable } from './deviceBindings';
import { createActivityLogTable } from './activityLog';

export function initializeTables() {
  createUsersTable();
  createDeviceBindingsTable();
  createActivityLogTable();
}

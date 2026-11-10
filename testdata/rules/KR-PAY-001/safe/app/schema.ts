import { pgTable, text } from "drizzle-orm/pg-core";

export const virtualAccounts = pgTable("virtual_accounts", {
  orderId: text("order_id").primaryKey(),
  transactionKey: text("transaction_key").notNull(),
  secret: text("secret").notNull(),
});

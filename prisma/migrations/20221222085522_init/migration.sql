/*
  Warnings:

  - You are about to drop the column `app` on the `tokens` table. All the data in the column will be lost.
  - You are about to drop the column `device` on the `tokens` table. All the data in the column will be lost.
  - You are about to drop the `providers` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "providers" DROP CONSTRAINT "providers_userId_fkey";

-- AlterTable
ALTER TABLE "tokens" DROP COLUMN "app",
DROP COLUMN "device";

-- DropTable
DROP TABLE "providers";

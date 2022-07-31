/*
  Warnings:

  - You are about to drop the column `browserInfo` on the `tokens` table. All the data in the column will be lost.
  - You are about to drop the column `refreshTokens` on the `users` table. All the data in the column will be lost.
  - Added the required column `appType` to the `tokens` table without a default value. This is not possible if the table is not empty.
  - Added the required column `device` to the `tokens` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "tokens" DROP COLUMN "browserInfo",
ADD COLUMN     "appType" TEXT NOT NULL,
ADD COLUMN     "device" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "users" DROP COLUMN "refreshTokens";

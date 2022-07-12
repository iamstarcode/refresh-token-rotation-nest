/*
  Warnings:

  - You are about to drop the column `currentHashedRefreshToken` on the `users` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "users" DROP COLUMN "currentHashedRefreshToken",
ADD COLUMN     "currentHashedRefreshTokens" TEXT[];

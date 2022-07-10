-- AlterTable
ALTER TABLE "users" ADD COLUMN     "currentHashedRefreshToken" TEXT,
ADD COLUMN     "isTwoFactorAuthenticationEnabled" TEXT;

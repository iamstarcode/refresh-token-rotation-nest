-- DropForeignKey
ALTER TABLE "providers" DROP CONSTRAINT "providers_userId_fkey";

-- AddForeignKey
ALTER TABLE "providers" ADD CONSTRAINT "providers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

export interface ITokenPayload {
  sub: number;
  email: string;
  isSecondFactorAuthenticated?: boolean;
}

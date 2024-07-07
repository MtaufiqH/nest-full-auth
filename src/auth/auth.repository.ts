import { AuthDto } from "./dto"

export interface AuthRepository {
    signIn(dto: AuthDto)
    signUp(dto: AuthDto)
}
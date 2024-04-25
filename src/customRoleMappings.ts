export type CustomRoleMappings = {
    customRoleMappings: CustomRoleMapping[]
}

export type CustomRoleMapping = {
    customRoleMappingId: string
    customRoleMappingName: string
    numOrgsSubscribed: number
}
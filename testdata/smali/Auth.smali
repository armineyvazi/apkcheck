.method public authenticate(Ljava/lang/String;)Z
    .locals 2
    const-string v0, "secret"
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    if-eqz v1, :fail
    return v1
    :fail
    const/4 v1, 0x0
    return v1
.end method

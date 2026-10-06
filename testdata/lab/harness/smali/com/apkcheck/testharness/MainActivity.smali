.class public Lcom/apkcheck/testharness/MainActivity;
.super Landroid/app/Activity;
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    const-string v0, "APKCheck authorized test harness"
    invoke-virtual {p0, v0}, Lcom/apkcheck/testharness/MainActivity;->setTitle(Ljava/lang/CharSequence;)V
    return-void
.end method

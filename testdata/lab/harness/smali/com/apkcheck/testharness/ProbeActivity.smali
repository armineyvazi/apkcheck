.class public Lcom/apkcheck/testharness/ProbeActivity;
.super Landroid/app/Activity;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 6
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    const-string v0, "apkcheck-harness"
    const-string v1, "PROBE_START authorized stealth probe"
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    # Try launch Divar MAIN/LAUNCHER (cross-app start — evidence in logcat + activity dumps)
    :try_start_launch
    new-instance v2, Landroid/content/Intent;
    const-string v3, "android.intent.action.MAIN"
    invoke-direct {v2, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    const-string v3, "android.intent.category.LAUNCHER"
    invoke-virtual {v2, v3}, Landroid/content/Intent;->addCategory(Ljava/lang/String;)Landroid/content/Intent;
    const-string v3, "ir.divar"
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;
    const/high16 v3, 0x10000000
    invoke-virtual {v2, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;
    invoke-virtual {p0, v2}, Lcom/apkcheck/testharness/ProbeActivity;->startActivity(Landroid/content/Intent;)V
    const-string v1, "PROBE_LAUNCH_DIVAR_OK"
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_launch
    .catch Ljava/lang/Exception; {:try_start_launch .. :try_end_launch} :catch_launch
    goto :after_launch

    :catch_launch
    move-exception v4
    const-string v1, "PROBE_LAUNCH_DIVAR_FAIL"
    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    :after_launch
    # Try VIEW divar:// deep link
    :try_start_view
    new-instance v2, Landroid/content/Intent;
    const-string v3, "android.intent.action.VIEW"
    invoke-direct {v2, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    const-string v3, "divar://"
    invoke-static {v3}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v3
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;
    const/high16 v3, 0x10000000
    invoke-virtual {v2, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;
    invoke-virtual {p0, v2}, Lcom/apkcheck/testharness/ProbeActivity;->startActivity(Landroid/content/Intent;)V
    const-string v1, "PROBE_VIEW_DIVAR_OK"
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_view
    .catch Ljava/lang/Exception; {:try_start_view .. :try_end_view} :catch_view
    goto :done

    :catch_view
    move-exception v4
    const-string v1, "PROBE_VIEW_DIVAR_FAIL"
    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    :done
    const-string v1, "PROBE_DONE"
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    invoke-virtual {p0}, Lcom/apkcheck/testharness/ProbeActivity;->finish()V
    return-void
.end method

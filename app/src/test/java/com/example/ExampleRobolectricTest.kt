package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    val devName = context.getString(R.string.developer_name)
    val telegram = context.getString(R.string.telegram_handle)
    assertEquals("Custom Tunnel Pro", appName)
    assertEquals("Liaqat Ali", devName)
    assertEquals("@LiaqatAliPro", telegram)
  }
}

package com.topjohnwu.magisk.ui.settings

import android.content.Context
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup.MarginLayoutParams
import androidx.appcompat.util.SeslRoundedCorner
import androidx.appcompat.util.SeslSubheaderRoundedCorner
import androidx.recyclerview.widget.RecyclerView
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.arch.BaseFragment
import com.topjohnwu.magisk.arch.viewModel
import com.topjohnwu.magisk.databinding.FragmentSettingsMd2Binding
import rikka.recyclerview.fixEdgeEffect

class SettingsFragment : BaseFragment<FragmentSettingsMd2Binding>() {

    override val layoutRes = R.layout.fragment_settings_md2
    override val viewModel by viewModel<SettingsViewModel>()
    override val snackbarView: View get() = binding.snackbarContainer

    override fun onStart() {
        super.onStart()

        activity?.title = resources.getString(R.string.settings)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.settingsList.apply {
            //addEdgeSpacing(bottom = R.dimen.l1)
            //addItemSpacing(R.dimen.l1, R.dimen.l_50, R.dimen.l1)
            seslSetFillBottomEnabled(true)
            addItemDecoration(ItemDecoration(context))
            fixEdgeEffect()
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.items.forEach { it.refresh() }
    }

    inner class ItemDecoration(context: Context) : RecyclerView.ItemDecoration() {
        private val mDivider: Drawable?
        private val mRoundedCorner: SeslSubheaderRoundedCorner

        init {
            val outValue = TypedValue()
            context.theme.resolveAttribute(
                dev.oneuiproject.oneui.R.attr.isLightTheme,
                outValue,
                true
            )
            mDivider =
                context.getDrawable(
                    if (outValue.data == 0)
                        dev.oneuiproject.oneui.R.drawable.sesl_list_divider_dark else
                        dev.oneuiproject.oneui.R.drawable.sesl_list_divider_light
                )
            mRoundedCorner = SeslSubheaderRoundedCorner(context)
            mRoundedCorner.roundedCorners = SeslRoundedCorner.ROUNDED_CORNER_ALL
        }

        override fun onDraw(
            c: Canvas, parent: RecyclerView,
            state: RecyclerView.State
        ) {
            super.onDraw(c, parent, state)
            for (i in 0 until parent.childCount) {
                val child = parent.getChildAt(i)
                if (viewModel.items[parent.getChildAdapterPosition(child)] !is BaseSettingsItem.Section) {
                    val top =
                        (child.bottom + (child.layoutParams as MarginLayoutParams).bottomMargin)
                    val bottom = mDivider!!.intrinsicHeight + top
                    mDivider.setBounds(parent.left, top, parent.right, bottom)
                    mDivider.draw(c)
                }
            }
        }

        override fun seslOnDispatchDraw(
            c: Canvas,
            parent: RecyclerView,
            state: RecyclerView.State
        ) {
            for (i in 0 until parent.childCount) {
                val child = parent.getChildAt(i)
                if (viewModel.items[parent.getChildAdapterPosition(child)] is BaseSettingsItem.Section) {
                    mRoundedCorner.drawRoundedCorner(child, c)
                }
            }
        }


    }

}

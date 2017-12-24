package com.pcapanalyzer.utils;

import java.awt.Dimension;
import java.awt.Toolkit;


public class WindowUtils {

	private static final Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
	
	private WindowUtils () {}
	

	public static int getScreenWidth () {
		return screenSize.width;
	}


	public static int getScreenHeight () {
		return screenSize.height;
	}
	
}

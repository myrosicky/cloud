package org.auth.util;

import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeUtil {

	private final static String dateFormat_yyyymmddhhmiss_underscore = "yyyy-MM-dd HH:mm:ss";
	private final static SimpleDateFormat sdf = new SimpleDateFormat(dateFormat_yyyymmddhhmiss_underscore);
	
	public static String getCurrentTime(){
		return sdf.format(new Date());
	}
}

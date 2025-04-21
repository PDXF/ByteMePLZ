"use client"

import { useTheme } from "next-themes"
import { useEffect, useState } from "react"
import { Moon, Sun } from "lucide-react"
import { motion } from "framer-motion"

export function ThemeToggle() {
  const [mounted, setMounted] = useState(false)
  const { theme, setTheme } = useTheme()
  const [isAnimating, setIsAnimating] = useState(false)

  // After mounting, we can safely show the UI
  useEffect(() => {
    setMounted(true)
  }, [])

  const toggleTheme = () => {
    setIsAnimating(true)
    setTheme(theme === "dark" ? "light" : "dark")
    setTimeout(() => setIsAnimating(false), 500)
  }

  if (!mounted) {
    return null
  }

  const isDark = theme === "dark"

  return (
    <div
      className="flex items-center cursor-pointer"
      onClick={toggleTheme}
      role="switch"
      aria-checked={isDark}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          toggleTheme()
        }
      }}
    >
      <div
        className={`w-12 h-6 flex items-center rounded-full p-1 ${isDark ? "bg-purple-700" : "bg-gray-300"} transition-colors duration-300`}
      >
        <motion.div
          className={`bg-white w-5 h-5 rounded-full shadow-md flex items-center justify-center ${isAnimating ? "animate-pulse" : ""}`}
          animate={{
            x: isDark ? 24 : 0,
          }}
          transition={{ type: "spring", stiffness: 700, damping: 30 }}
        >
          {isDark ? <Moon className="h-3 w-3 text-purple-700" /> : <Sun className="h-3 w-3 text-amber-500" />}
        </motion.div>
      </div>
    </div>
  )
}

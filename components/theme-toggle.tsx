"use client"

import { useTheme } from "next-themes"
import { useEffect, useState } from "react"
import { Moon, Sun } from "lucide-react"
import { motion, AnimatePresence } from "framer-motion"

export function ThemeToggle() {
  const [mounted, setMounted] = useState(false)
  const { theme, resolvedTheme, setTheme } = useTheme()
  const [isAnimating, setIsAnimating] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  const currentTheme = theme === "system" ? resolvedTheme : theme
  const isDark = currentTheme === "dark"

  const toggleTheme = () => {
    setIsAnimating(true)
    setTheme(isDark ? "light" : "dark")
    setTimeout(() => setIsAnimating(false), 500)
  }

  if (!mounted) return null

  return (
    <div
      className="flex items-center cursor-pointer outline-none"
      onClick={toggleTheme}
      role="switch"
      aria-checked={isDark}
      aria-label="Toggle dark mode"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") toggleTheme()
      }}
    >
      <motion.div
        className="w-12 h-6 rounded-full p-1 flex items-center"
        initial={false}
        animate={{
          backgroundColor: isDark ? "#6B21A8" : "#D1D5DB", // Tailwind: purple-700 or gray-300
        }}
        transition={{ duration: 0.4 }}
      >
        <motion.div
          className="w-5 h-5 rounded-full shadow-md bg-white flex items-center justify-center"
          animate={{
            x: isDark ? 24 : 0,
            scale: isAnimating ? 1.1 : 1,
          }}
          transition={{ type: "spring", stiffness: 500, damping: 30 }}
        >
          <AnimatePresence mode="wait">
            {isDark ? (
              <motion.div
                key="moon"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
              >
                <Moon className="h-3 w-3 text-purple-700" />
              </motion.div>
            ) : (
              <motion.div
                key="sun"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
              >
                <Sun className="h-3 w-3 text-amber-500" />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </motion.div>
    </div>
  )
}

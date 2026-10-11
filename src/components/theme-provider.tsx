import type { ComponentProps } from "react";
import { ThemeProvider as NextThemesProvider } from "next-themes";

type ThemeProviderProps = ComponentProps<typeof NextThemesProvider>;

/**
 * 主题名 → <html> class 映射。「少女粉」落为 `theme-pink`（token 见 index.css），
 * light/dark 保持原 class 名不变。
 * 注意：映射必须完整覆盖 light/dark——next-themes 会取 Object.values(value)
 * 作为切换时的 class 移除清单，漏写任意一项都会导致旧 class 残留。
 */
const THEME_CLASS_MAP = {
  light: "light",
  dark: "dark",
  pink: "theme-pink",
} as const;

/**
 * Dark-first theme provider. Toggles the `dark` class on <html>, persists the
 * choice in localStorage and follows the OS setting when set to "system".
 *
 * 第三套主题「少女粉」是独立的浅色套装，不参与 system 解析
 * （system 只解析 light/dark，pink 选中后不随系统深浅色切换）。
 * color-scheme 交由 index.css 按主题 class 声明：next-themes 的内联
 * colorScheme 在自定义主题下会按 defaultTheme 误设为 dark。
 */
export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem
      enableColorScheme={false}
      disableTransitionOnChange
      themes={["light", "dark", "pink"]}
      value={THEME_CLASS_MAP}
      {...props}
    >
      {children}
    </NextThemesProvider>
  );
}

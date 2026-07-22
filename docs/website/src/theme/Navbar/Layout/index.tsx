import React, { useEffect, useState } from "react";
import clsx from "clsx";
import { useThemeConfig } from "@docusaurus/theme-common";
import {
  useHideableNavbar,
  useNavbarMobileSidebar,
} from "@docusaurus/theme-common/internal";
import { translate } from "@docusaurus/Translate";
import NavbarMobileSidebar from "@theme/Navbar/MobileSidebar";
import styles from "./styles.module.css";
import { useIsLandingPage } from "../../../hooks/useIsLandingPage";

function NavbarBackdrop(props) {
  return (
    <div
      role="presentation"
      {...props}
      className={clsx("navbar-sidebar__backdrop", props.className)}
    />
  );
}

export default function NavbarLayout({ children }) {
  const isLandingPage = useIsLandingPage();
  const {
    navbar: { hideOnScroll },
  } = useThemeConfig();
  const mobileSidebar = useNavbarMobileSidebar();
  const { navbarRef, isNavbarVisible } = useHideableNavbar(hideOnScroll);

  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      setScrolled(window.scrollY > 70);
    };

    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      ref={navbarRef}
      aria-label={translate({
        id: "theme.NavBar.navAriaLabel",
        message: "Main",
        description: "The ARIA label for the main navigation",
      })}
      className={clsx(
        "flex navbar tablet:py-[30px] px-0! shadow-none z-50",
        isLandingPage
          ? "border-none pt-3"
          : "border-b border-[#EAEAEB] pt-3 pb-4 tablet:px-2",
        "navbar--fixed-top",
        hideOnScroll && !isNavbarVisible && styles.navbarHidden,
        {
          "navbar-sidebar--show": mobileSidebar.shown,
          "landing-navbar--scrolled": isLandingPage && scrolled,
          "landing-navbar--top": isLandingPage && !scrolled,
        },
      )}
    >
      <div
        className={clsx(
          isLandingPage ? "pageContainer py-0.5 tablet:py-0" : "w-full px-6",
        )}
      >
        {children}
      </div>
      <NavbarBackdrop onClick={mobileSidebar.toggle} />
      <NavbarMobileSidebar />
    </header>
  );
}

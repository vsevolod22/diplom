import type { ComponentProps } from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';

// Adapted from shadcn/ui Tabs (21st.dev): keep Radix's keyboard and ARIA behaviour.
export function GuideTabs({ className = '', ...props }: ComponentProps<typeof TabsPrimitive.Root>) {
  return <TabsPrimitive.Root data-slot="tabs" className={`scan-guide-tabs ${className}`} {...props} />;
}

export function GuideTabsList(props: ComponentProps<typeof TabsPrimitive.List>) {
  return <TabsPrimitive.List data-slot="tabs-list" className="scan-guide-tabs__list" {...props} />;
}

export function GuideTabsTrigger(props: ComponentProps<typeof TabsPrimitive.Trigger>) {
  return <TabsPrimitive.Trigger data-slot="tabs-trigger" className="scan-guide-tabs__trigger" {...props} />;
}

export function GuideTabsContent(props: ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content data-slot="tabs-content" className="scan-guide-tabs__content" {...props} />;
}
